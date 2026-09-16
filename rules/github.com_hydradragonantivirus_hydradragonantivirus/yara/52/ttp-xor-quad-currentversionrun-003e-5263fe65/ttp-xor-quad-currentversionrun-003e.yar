rule TTP_XOR_QUAD_CurrentVersionRun_003e {
  strings:
    $key_003e = { 53 51 [2] 77 5f [2] 5c 73 [2] 72 51 [2] 66 4a [2] 69 50 [2] 77 4d [2] 75 4c [2] 6e 4a [2] 72 4d [2] 6e 62 }

  condition:
    any of them
}