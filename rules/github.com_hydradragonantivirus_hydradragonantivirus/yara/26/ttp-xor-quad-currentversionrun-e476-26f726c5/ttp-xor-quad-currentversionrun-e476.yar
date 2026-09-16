rule TTP_XOR_QUAD_CurrentVersionRun_e476 {
  strings:
    $key_e476 = { b7 19 [2] 93 17 [2] b8 3b [2] 96 19 [2] 82 02 [2] 8d 18 [2] 93 05 [2] 91 04 [2] 8a 02 [2] 96 05 [2] 8a 2a }

  condition:
    any of them
}