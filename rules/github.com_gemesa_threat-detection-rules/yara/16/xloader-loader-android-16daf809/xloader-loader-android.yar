rule xloader_loader_android {
  meta:
    description = "XLoader loader (Android)"
    author = "Andras Gemes"
    date = "2025-12-14"
    sha256 = "02c08ec2675abe6e09691419dd1a281194879c6e393de1cdfb150b864378d921"
    ref1 = "https://shadowshell.io/xloader"
    ref2 = "https://bazaar.abuse.ch/sample/02c08ec2675abe6e09691419dd1a281194879c6e393de1cdfb150b864378d921/"

  strings:
                $package = "qqfzq.oeoop.lr.xnzcwr" ascii wide

            $permission0 = "sedv.yfem.nfjzi" ascii wide
        $permission1 = "pfoph.ryxrplq.dyek" ascii wide
        $permission2 = "rzcad.qkwoooz.ualxq" ascii wide
        $permission3 = "bcemr.fjshnci.xfanv" ascii wide
        $permission4 = "qrzsznko.gsgeyz.fztiy" ascii wide
        $permission5 = "pphnxshu.bhxe.rxgklxny" ascii wide

            $pc0 = "gf6h8y8.GNuApplication" ascii wide
        $pc1 = "gf6h8y8.CrActivity" ascii wide
        $pc2 = "gf6h8y8.Ux" ascii wide
        $pc3 = "gf6h8y8.Ry" ascii wide
        $pc4 = "gf6h8y8.Jz" ascii wide
        $pc5 = "gf6h8y8.Li" ascii wide
        $pc6 = "gf6h8y8.Ap" ascii wide
        $pc7 = "gf6h8y8.Yi" ascii wide

  condition:
    10 of them
}