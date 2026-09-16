rule TTP_XOR_QUAD_CurrentVersionRun_d9f0 {
  strings:
    $key_d9f0 = { 8a 9f [2] ae 91 [2] 85 bd [2] ab 9f [2] bf 84 [2] b0 9e [2] ae 83 [2] ac 82 [2] b7 84 [2] ab 83 [2] b7 ac }

  condition:
    any of them
}