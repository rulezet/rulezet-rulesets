rule TTP_XOR_QUAD_CurrentVersionRun_e411 {
  strings:
    $key_e411 = { b7 7e [2] 93 70 [2] b8 5c [2] 96 7e [2] 82 65 [2] 8d 7f [2] 93 62 [2] 91 63 [2] 8a 65 [2] 96 62 [2] 8a 4d }

  condition:
    any of them
}