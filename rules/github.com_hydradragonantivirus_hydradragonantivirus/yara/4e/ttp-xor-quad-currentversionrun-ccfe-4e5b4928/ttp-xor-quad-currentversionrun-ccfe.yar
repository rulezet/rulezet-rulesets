rule TTP_XOR_QUAD_CurrentVersionRun_ccfe {
  strings:
    $key_ccfe = { 9f 91 [2] bb 9f [2] 90 b3 [2] be 91 [2] aa 8a [2] a5 90 [2] bb 8d [2] b9 8c [2] a2 8a [2] be 8d [2] a2 a2 }

  condition:
    any of them
}