rule TTP_XOR_QUAD_CurrentVersionRun_c4be {
  strings:
    $key_c4be = { 97 d1 [2] b3 df [2] 98 f3 [2] b6 d1 [2] a2 ca [2] ad d0 [2] b3 cd [2] b1 cc [2] aa ca [2] b6 cd [2] aa e2 }

  condition:
    any of them
}