rule TTP_XOR_QUAD_CurrentVersionRun_db8f {
  strings:
    $key_db8f = { 88 e0 [2] ac ee [2] 87 c2 [2] a9 e0 [2] bd fb [2] b2 e1 [2] ac fc [2] ae fd [2] b5 fb [2] a9 fc [2] b5 d3 }

  condition:
    any of them
}