rule tool_network_free_code {
  meta:
    description = "Identify executables with domains with free hosting of code."
    author      = "@shellcromancer"
    version     = "1.0"
    date        = "2023.01.05"
    DaysofYARA  = "5/100"

  strings:
    $cf_workers = ".workers.dev" xor
    $cf_pages   = ".pages.dev" xor
    $vercel_app = ".vercel.app" xor
    $vercel_dev = ".vercel.dev" xor
    $vercel_now = ".now.sh" xor
    $deno       = ".deno.dev" xor
    $fly        = ".fly.dev" xor
    $deta       = ".deta.dev" xor

  condition:
    (
      int16(0) == 0x5a4d or        uint32(0) == 0x464c457f or        uint32(0) == 0xfeedface or        uint32(0) == 0xcefaedfe or        uint32(0) == 0xfeedfacf or        uint32(0) == 0xcffaedfe or        uint32(0) == 0xcafebabe or        uint32(0) == 0xbebafeca      ) and
    any of them
}