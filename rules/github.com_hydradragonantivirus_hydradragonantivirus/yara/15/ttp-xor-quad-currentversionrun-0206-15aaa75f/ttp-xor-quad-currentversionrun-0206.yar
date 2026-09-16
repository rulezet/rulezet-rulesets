rule TTP_XOR_QUAD_CurrentVersionRun_0206 {
  strings:
    $key_0206 = { 51 69 [2] 75 67 [2] 5e 4b [2] 70 69 [2] 64 72 [2] 6b 68 [2] 75 75 [2] 77 74 [2] 6c 72 [2] 70 75 [2] 6c 5a }

  condition:
    any of them
}