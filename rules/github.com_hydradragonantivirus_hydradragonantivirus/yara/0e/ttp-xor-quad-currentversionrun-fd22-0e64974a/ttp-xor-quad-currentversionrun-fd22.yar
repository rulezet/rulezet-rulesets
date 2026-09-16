rule TTP_XOR_QUAD_CurrentVersionRun_fd22 {
  strings:
    $key_fd22 = { ae 4d [2] 8a 43 [2] a1 6f [2] 8f 4d [2] 9b 56 [2] 94 4c [2] 8a 51 [2] 88 50 [2] 93 56 [2] 8f 51 [2] 93 7e }

  condition:
    any of them
}