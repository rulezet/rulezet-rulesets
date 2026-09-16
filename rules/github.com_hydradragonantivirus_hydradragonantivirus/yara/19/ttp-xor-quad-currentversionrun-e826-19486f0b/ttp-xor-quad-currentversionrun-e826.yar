rule TTP_XOR_QUAD_CurrentVersionRun_e826 {
  strings:
    $key_e826 = { bb 49 [2] 9f 47 [2] b4 6b [2] 9a 49 [2] 8e 52 [2] 81 48 [2] 9f 55 [2] 9d 54 [2] 86 52 [2] 9a 55 [2] 86 7a }

  condition:
    any of them
}