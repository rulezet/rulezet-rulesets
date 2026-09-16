rule TTP_XOR_QUAD_CurrentVersionRun_d922 {
  strings:
    $key_d922 = { 8a 4d [2] ae 43 [2] 85 6f [2] ab 4d [2] bf 56 [2] b0 4c [2] ae 51 [2] ac 50 [2] b7 56 [2] ab 51 [2] b7 7e }

  condition:
    any of them
}