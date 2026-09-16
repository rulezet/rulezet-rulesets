rule SUSP_kernel32_mutation_rot13_xor {
  meta:
    author      = "Greg Lesnewich"
    description = "track string mutations of kernel32 which can be used for lots of evil things"
    date        = "2024-01-24"
    version     = "1.0"
    DaysofYARA  = "24/100"

  strings:
    $kernel32_rot13_xor = "xreary32" xor(0x01-0xff) ascii wide

  condition:
    all of them
}