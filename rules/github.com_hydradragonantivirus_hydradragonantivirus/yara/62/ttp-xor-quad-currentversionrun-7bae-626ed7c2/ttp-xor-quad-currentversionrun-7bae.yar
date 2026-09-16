rule TTP_XOR_QUAD_CurrentVersionRun_7bae {
  strings:
    $key_7bae = { 28 c1 [2] 0c cf [2] 27 e3 [2] 09 c1 [2] 1d da [2] 12 c0 [2] 0c dd [2] 0e dc [2] 15 da [2] 09 dd [2] 15 f2 }

  condition:
    any of them
}