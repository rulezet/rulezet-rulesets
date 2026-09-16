rule TTP_XOR_QUAD_CurrentVersionRun_2bae {
  strings:
    $key_2bae = { 78 c1 [2] 5c cf [2] 77 e3 [2] 59 c1 [2] 4d da [2] 42 c0 [2] 5c dd [2] 5e dc [2] 45 da [2] 59 dd [2] 45 f2 }

  condition:
    any of them
}