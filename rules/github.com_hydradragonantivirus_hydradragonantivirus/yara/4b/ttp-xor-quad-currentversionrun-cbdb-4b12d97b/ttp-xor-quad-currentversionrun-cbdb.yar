rule TTP_XOR_QUAD_CurrentVersionRun_cbdb {
  strings:
    $key_cbdb = { 98 b4 [2] bc ba [2] 97 96 [2] b9 b4 [2] ad af [2] a2 b5 [2] bc a8 [2] be a9 [2] a5 af [2] b9 a8 [2] a5 87 }

  condition:
    any of them
}