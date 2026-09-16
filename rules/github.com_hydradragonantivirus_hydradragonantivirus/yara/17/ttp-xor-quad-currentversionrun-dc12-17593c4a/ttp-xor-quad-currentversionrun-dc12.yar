rule TTP_XOR_QUAD_CurrentVersionRun_dc12 {
  strings:
    $key_dc12 = { 8f 7d [2] ab 73 [2] 80 5f [2] ae 7d [2] ba 66 [2] b5 7c [2] ab 61 [2] a9 60 [2] b2 66 [2] ae 61 [2] b2 4e }

  condition:
    any of them
}