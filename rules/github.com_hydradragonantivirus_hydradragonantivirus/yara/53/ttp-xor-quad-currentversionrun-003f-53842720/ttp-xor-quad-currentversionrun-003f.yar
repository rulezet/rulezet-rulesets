rule TTP_XOR_QUAD_CurrentVersionRun_003f {
  strings:
    $key_003f = { 53 50 [2] 77 5e [2] 5c 72 [2] 72 50 [2] 66 4b [2] 69 51 [2] 77 4c [2] 75 4d [2] 6e 4b [2] 72 4c [2] 6e 63 }

  condition:
    any of them
}