rule TTP_XOR_QUAD_CurrentVersionRun_dc0c {
  strings:
    $key_dc0c = { 8f 63 [2] ab 6d [2] 80 41 [2] ae 63 [2] ba 78 [2] b5 62 [2] ab 7f [2] a9 7e [2] b2 78 [2] ae 7f [2] b2 50 }

  condition:
    any of them
}