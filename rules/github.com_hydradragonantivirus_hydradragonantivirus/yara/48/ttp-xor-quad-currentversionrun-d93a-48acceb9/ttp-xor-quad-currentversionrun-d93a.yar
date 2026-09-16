rule TTP_XOR_QUAD_CurrentVersionRun_d93a {
  strings:
    $key_d93a = { 8a 55 [2] ae 5b [2] 85 77 [2] ab 55 [2] bf 4e [2] b0 54 [2] ae 49 [2] ac 48 [2] b7 4e [2] ab 49 [2] b7 66 }

  condition:
    any of them
}