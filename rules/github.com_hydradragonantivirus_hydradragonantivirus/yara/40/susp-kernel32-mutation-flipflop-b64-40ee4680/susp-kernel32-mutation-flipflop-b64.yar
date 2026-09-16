rule SUSP_kernel32_mutation_flipflop_b64 {
  meta:
    author      = "Greg Lesnewich"
    description = "track string mutations of kernel32 which can be used for lots of evil things"
    date        = "2024-01-24"
    version     = "1.0"
    DaysofYARA  = "24/100"

  strings:
    $kernel32_flipflop_b64 = "eknrle23" base64 base64wide

  condition:
    all of them
}