rule TTP_XOR_QUAD_CurrentVersionRun_92ab {
  strings:
    $key_92ab = { c1 c4 [2] e5 ca [2] ce e6 [2] e0 c4 [2] f4 df [2] fb c5 [2] e5 d8 [2] e7 d9 [2] fc df [2] e0 d8 [2] fc f7 }

  condition:
    any of them
}