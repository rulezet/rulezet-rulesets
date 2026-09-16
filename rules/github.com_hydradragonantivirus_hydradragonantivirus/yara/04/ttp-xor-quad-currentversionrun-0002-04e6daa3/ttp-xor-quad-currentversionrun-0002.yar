rule TTP_XOR_QUAD_CurrentVersionRun_0002 {
  strings:
    $key_0002 = { 53 6d [2] 77 63 [2] 5c 4f [2] 72 6d [2] 66 76 [2] 69 6c [2] 77 71 [2] 75 70 [2] 6e 76 [2] 72 71 [2] 6e 5e }

  condition:
    any of them
}