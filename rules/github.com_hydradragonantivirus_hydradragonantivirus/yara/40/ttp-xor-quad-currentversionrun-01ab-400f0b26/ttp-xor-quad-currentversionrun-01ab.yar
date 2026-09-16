rule TTP_XOR_QUAD_CurrentVersionRun_01ab {
  strings:
    $key_01ab = { 52 c4 [2] 76 ca [2] 5d e6 [2] 73 c4 [2] 67 df [2] 68 c5 [2] 76 d8 [2] 74 d9 [2] 6f df [2] 73 d8 [2] 6f f7 }

  condition:
    any of them
}