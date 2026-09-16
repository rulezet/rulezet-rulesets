rule TTP_XOR_QUAD_CurrentVersionRun_c722 {
  strings:
    $key_c722 = { 94 4d [2] b0 43 [2] 9b 6f [2] b5 4d [2] a1 56 [2] ae 4c [2] b0 51 [2] b2 50 [2] a9 56 [2] b5 51 [2] a9 7e }

  condition:
    any of them
}