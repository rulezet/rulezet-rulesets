rule TTP_XOR_QUAD_CurrentVersionRun_c48f {
  strings:
    $key_c48f = { 97 e0 [2] b3 ee [2] 98 c2 [2] b6 e0 [2] a2 fb [2] ad e1 [2] b3 fc [2] b1 fd [2] aa fb [2] b6 fc [2] aa d3 }

  condition:
    any of them
}