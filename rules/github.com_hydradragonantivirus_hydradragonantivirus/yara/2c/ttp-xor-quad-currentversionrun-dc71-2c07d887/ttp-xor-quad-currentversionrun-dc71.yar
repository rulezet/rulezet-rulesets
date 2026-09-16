rule TTP_XOR_QUAD_CurrentVersionRun_dc71 {
  strings:
    $key_dc71 = { 8f 1e [2] ab 10 [2] 80 3c [2] ae 1e [2] ba 05 [2] b5 1f [2] ab 02 [2] a9 03 [2] b2 05 [2] ae 02 [2] b2 2d }

  condition:
    any of them
}