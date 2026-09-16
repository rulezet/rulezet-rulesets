rule SUSP_kernel32_mutation_stackpush {
  meta:
    author      = "Greg Lesnewich"
    description = "track string mutations of kernel32 which can be used for lots of evil things"
    date        = "2024-01-24"
    version     = "1.0"
    DaysofYARA  = "24/100"

  strings:
    $kernel32_stackpush = "hel32hkern" nocase ascii wide

  condition:
    all of them
}