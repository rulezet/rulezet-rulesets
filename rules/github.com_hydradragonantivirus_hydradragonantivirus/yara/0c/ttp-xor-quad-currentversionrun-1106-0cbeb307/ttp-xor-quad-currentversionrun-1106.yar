rule TTP_XOR_QUAD_CurrentVersionRun_1106 {
  strings:
    $key_1106 = { 42 69 [2] 66 67 [2] 4d 4b [2] 63 69 [2] 77 72 [2] 78 68 [2] 66 75 [2] 64 74 [2] 7f 72 [2] 63 75 [2] 7f 5a }

  condition:
    any of them
}