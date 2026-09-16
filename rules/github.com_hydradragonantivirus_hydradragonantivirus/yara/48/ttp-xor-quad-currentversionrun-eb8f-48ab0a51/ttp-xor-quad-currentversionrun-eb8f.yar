rule TTP_XOR_QUAD_CurrentVersionRun_eb8f {
  strings:
    $key_eb8f = { b8 e0 [2] 9c ee [2] b7 c2 [2] 99 e0 [2] 8d fb [2] 82 e1 [2] 9c fc [2] 9e fd [2] 85 fb [2] 99 fc [2] 85 d3 }

  condition:
    any of them
}