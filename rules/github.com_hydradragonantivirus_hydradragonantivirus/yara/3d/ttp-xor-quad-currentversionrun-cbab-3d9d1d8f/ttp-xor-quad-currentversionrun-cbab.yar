rule TTP_XOR_QUAD_CurrentVersionRun_cbab {
  strings:
    $key_cbab = { 98 c4 [2] bc ca [2] 97 e6 [2] b9 c4 [2] ad df [2] a2 c5 [2] bc d8 [2] be d9 [2] a5 df [2] b9 d8 [2] a5 f7 }

  condition:
    any of them
}