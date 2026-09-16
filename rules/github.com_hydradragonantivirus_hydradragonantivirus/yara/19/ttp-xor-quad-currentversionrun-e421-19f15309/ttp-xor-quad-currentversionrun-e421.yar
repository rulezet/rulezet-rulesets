rule TTP_XOR_QUAD_CurrentVersionRun_e421 {
  strings:
    $key_e421 = { b7 4e [2] 93 40 [2] b8 6c [2] 96 4e [2] 82 55 [2] 8d 4f [2] 93 52 [2] 91 53 [2] 8a 55 [2] 96 52 [2] 8a 7d }

  condition:
    any of them
}