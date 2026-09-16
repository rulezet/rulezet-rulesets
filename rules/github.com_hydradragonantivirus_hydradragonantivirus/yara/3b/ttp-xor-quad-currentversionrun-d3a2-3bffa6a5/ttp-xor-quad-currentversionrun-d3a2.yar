rule TTP_XOR_QUAD_CurrentVersionRun_d3a2 {
  strings:
    $key_d3a2 = { 80 cd [2] a4 c3 [2] 8f ef [2] a1 cd [2] b5 d6 [2] ba cc [2] a4 d1 [2] a6 d0 [2] bd d6 [2] a1 d1 [2] bd fe }

  condition:
    any of them
}