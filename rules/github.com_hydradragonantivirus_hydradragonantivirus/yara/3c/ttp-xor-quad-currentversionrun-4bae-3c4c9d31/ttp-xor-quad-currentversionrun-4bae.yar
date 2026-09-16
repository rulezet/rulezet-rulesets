rule TTP_XOR_QUAD_CurrentVersionRun_4bae {
  strings:
    $key_4bae = { 18 c1 [2] 3c cf [2] 17 e3 [2] 39 c1 [2] 2d da [2] 22 c0 [2] 3c dd [2] 3e dc [2] 25 da [2] 39 dd [2] 25 f2 }

  condition:
    any of them
}