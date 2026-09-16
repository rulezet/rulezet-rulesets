rule TTP_XOR_QUAD_CurrentVersionRun_dc30 {
  strings:
    $key_dc30 = { 8f 5f [2] ab 51 [2] 80 7d [2] ae 5f [2] ba 44 [2] b5 5e [2] ab 43 [2] a9 42 [2] b2 44 [2] ae 43 [2] b2 6c }

  condition:
    any of them
}