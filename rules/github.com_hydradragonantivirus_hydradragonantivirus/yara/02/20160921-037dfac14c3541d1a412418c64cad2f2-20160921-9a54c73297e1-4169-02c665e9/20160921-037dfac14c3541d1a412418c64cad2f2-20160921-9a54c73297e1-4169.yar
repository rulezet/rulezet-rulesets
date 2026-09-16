rule _20160921_037dfac14c3541d1a412418c64cad2f2_20160921_9a54c73297e1_4169 {
  meta:
    description = "datamaliciousorder - from files 20160921_037dfac14c3541d1a412418c64cad2f2.js, 20160921_9a54c73297e1211ec78765c2c1c7c05b.js, 20160921_f1aea308b2000a8d722d0f21c756fabf.js, 20160922_e83e21df386eef1a99bc7a65e7e6f6f4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bdbf3b67df915739d64604188a4862042efa316e641ef50d228a41f9327767cc"
    hash2       = "3d2e8d0924bbdcf83eaa5ef9fde5baf8f4e12cf5c14d5f8ceb77a4c3e708abd3"
    hash3       = "3175e432bce3be89acef4ff7215de666ea47cac857c8c07ff649c1cdd5484103"
    hash4       = "ff3bd7f3bb53e5b0bbfefd44c539b38a506a76e4dae03eaa91c64f99e34b846b"

  strings:
    $s1 = "tion f000(){return \"OUx\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"PTs\";})(),(function f000(){retur" ascii
    $s2 = "return \"Oh\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(" ascii
    $s3 = "})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"MBb\";})(),(function f00" ascii
    $s4 = "a\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(functio" ascii
    $s5 = "){return \"Vu\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}