rule TTP_XOR_QUAD_CurrentVersionRun_000b {
  strings:
    $key_000b = { 53 64 [2] 77 6a [2] 5c 46 [2] 72 64 [2] 66 7f [2] 69 65 [2] 77 78 [2] 75 79 [2] 6e 7f [2] 72 78 [2] 6e 57 }

  condition:
    any of them
}