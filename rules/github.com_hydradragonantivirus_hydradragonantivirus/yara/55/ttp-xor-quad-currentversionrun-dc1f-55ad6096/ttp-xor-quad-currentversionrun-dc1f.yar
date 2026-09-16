rule TTP_XOR_QUAD_CurrentVersionRun_dc1f {
  strings:
    $key_dc1f = { 8f 70 [2] ab 7e [2] 80 52 [2] ae 70 [2] ba 6b [2] b5 71 [2] ab 6c [2] a9 6d [2] b2 6b [2] ae 6c [2] b2 43 }

  condition:
    any of them
}