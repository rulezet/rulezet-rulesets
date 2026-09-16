rule TTP_XOR_QUAD_CurrentVersionRun_0bae {
  strings:
    $key_0bae = { 58 c1 [2] 7c cf [2] 57 e3 [2] 79 c1 [2] 6d da [2] 62 c0 [2] 7c dd [2] 7e dc [2] 65 da [2] 79 dd [2] 65 f2 }

  condition:
    any of them
}