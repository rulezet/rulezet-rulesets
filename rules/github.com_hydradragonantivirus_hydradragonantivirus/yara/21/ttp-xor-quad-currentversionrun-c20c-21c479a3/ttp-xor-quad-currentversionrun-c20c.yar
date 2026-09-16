rule TTP_XOR_QUAD_CurrentVersionRun_c20c {
  strings:
    $key_c20c = { 91 63 [2] b5 6d [2] 9e 41 [2] b0 63 [2] a4 78 [2] ab 62 [2] b5 7f [2] b7 7e [2] ac 78 [2] b0 7f [2] ac 50 }

  condition:
    any of them
}