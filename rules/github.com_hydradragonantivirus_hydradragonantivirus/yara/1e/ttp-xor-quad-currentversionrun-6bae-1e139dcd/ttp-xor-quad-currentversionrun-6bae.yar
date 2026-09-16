rule TTP_XOR_QUAD_CurrentVersionRun_6bae {
  strings:
    $key_6bae = { 38 c1 [2] 1c cf [2] 37 e3 [2] 19 c1 [2] 0d da [2] 02 c0 [2] 1c dd [2] 1e dc [2] 05 da [2] 19 dd [2] 05 f2 }

  condition:
    any of them
}