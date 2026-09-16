rule TTP_XOR_QUAD_CurrentVersionRun_3bae {
  strings:
    $key_3bae = { 68 c1 [2] 4c cf [2] 67 e3 [2] 49 c1 [2] 5d da [2] 52 c0 [2] 4c dd [2] 4e dc [2] 55 da [2] 49 dd [2] 55 f2 }

  condition:
    any of them
}