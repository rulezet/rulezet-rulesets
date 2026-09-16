rule TTP_XOR_QUAD_CurrentVersionRun_3806 {
  strings:
    $key_3806 = { 6b 69 [2] 4f 67 [2] 64 4b [2] 4a 69 [2] 5e 72 [2] 51 68 [2] 4f 75 [2] 4d 74 [2] 56 72 [2] 4a 75 [2] 56 5a }

  condition:
    any of them
}