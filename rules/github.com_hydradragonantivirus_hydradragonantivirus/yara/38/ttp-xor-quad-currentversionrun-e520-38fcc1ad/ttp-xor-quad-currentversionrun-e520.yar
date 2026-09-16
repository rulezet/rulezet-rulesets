rule TTP_XOR_QUAD_CurrentVersionRun_e520 {
  strings:
    $key_e520 = { b6 4f [2] 92 41 [2] b9 6d [2] 97 4f [2] 83 54 [2] 8c 4e [2] 92 53 [2] 90 52 [2] 8b 54 [2] 97 53 [2] 8b 7c }

  condition:
    any of them
}