rule TTP_XOR_QUAD_CurrentVersionRun_c531 {
  strings:
    $key_c531 = { 96 5e [2] b2 50 [2] 99 7c [2] b7 5e [2] a3 45 [2] ac 5f [2] b2 42 [2] b0 43 [2] ab 45 [2] b7 42 [2] ab 6d }

  condition:
    any of them
}