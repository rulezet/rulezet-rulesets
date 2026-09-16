rule PEiD_02319_Unknown_packer__04__ {
  meta:
    description = "[Unknown packer (04)]"
    ep_only     = "true"

  strings:
    $a = { BC ?? ?? C3 2E FF 2E ?? ?? CF }

  condition:
    $a
}