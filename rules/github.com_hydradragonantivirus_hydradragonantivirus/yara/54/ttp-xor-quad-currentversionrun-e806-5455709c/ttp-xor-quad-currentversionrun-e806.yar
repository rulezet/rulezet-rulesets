rule TTP_XOR_QUAD_CurrentVersionRun_e806 {
  strings:
    $key_e806 = { bb 69 [2] 9f 67 [2] b4 4b [2] 9a 69 [2] 8e 72 [2] 81 68 [2] 9f 75 [2] 9d 74 [2] 86 72 [2] 9a 75 [2] 86 5a }

  condition:
    any of them
}