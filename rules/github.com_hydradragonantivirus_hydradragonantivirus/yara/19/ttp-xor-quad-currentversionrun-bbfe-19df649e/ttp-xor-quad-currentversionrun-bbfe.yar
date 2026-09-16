rule TTP_XOR_QUAD_CurrentVersionRun_bbfe {
  strings:
    $key_bbfe = { e8 91 [2] cc 9f [2] e7 b3 [2] c9 91 [2] dd 8a [2] d2 90 [2] cc 8d [2] ce 8c [2] d5 8a [2] c9 8d [2] d5 a2 }

  condition:
    any of them
}