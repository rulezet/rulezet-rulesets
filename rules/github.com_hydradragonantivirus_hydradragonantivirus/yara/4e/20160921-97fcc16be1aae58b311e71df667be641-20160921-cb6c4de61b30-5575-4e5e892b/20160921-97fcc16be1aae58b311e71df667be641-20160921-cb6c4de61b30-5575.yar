rule _20160921_97fcc16be1aae58b311e71df667be641_20160921_cb6c4de61b30_5575 {
  meta:
    description = "datamaliciousorder - from files 20160921_97fcc16be1aae58b311e71df667be641.js, 20160921_cb6c4de61b30cd204129d0942321058c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2459214bba37a40478bc984d75c7b1ababcbf0d17eeabe32578555058bdac21f"
    hash2       = "db98233c2508e4a2167ee46a334ce9052faa726615e89838f4fdb36b74fc5353"

  strings:
    $s1 = "),(function f000(){return \"GGn\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Kw\";})(),(function f000(){" ascii
    $s2 = "urn \"RPt\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(f" ascii
    $s3 = "function f000(){return \"Nv\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"KXg\";})(),(function f000(){ret" ascii
    $s4 = "e\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"TKp\";})(),(function " ascii
    $s5 = "n \"Mc\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"MMz\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}