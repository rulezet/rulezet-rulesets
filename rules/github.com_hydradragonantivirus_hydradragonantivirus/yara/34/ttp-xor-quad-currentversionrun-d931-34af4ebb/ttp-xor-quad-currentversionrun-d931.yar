rule TTP_XOR_QUAD_CurrentVersionRun_d931 {
  strings:
    $key_d931 = { 8a 5e [2] ae 50 [2] 85 7c [2] ab 5e [2] bf 45 [2] b0 5f [2] ae 42 [2] ac 43 [2] b7 45 [2] ab 42 [2] b7 6d }

  condition:
    any of them
}