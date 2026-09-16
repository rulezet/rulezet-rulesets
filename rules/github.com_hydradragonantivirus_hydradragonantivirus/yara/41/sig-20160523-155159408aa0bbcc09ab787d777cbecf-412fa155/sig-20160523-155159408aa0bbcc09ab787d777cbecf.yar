rule sig_20160523_155159408aa0bbcc09ab787d777cbecf {
  meta:
    description = "datamaliciousorder - file 20160523_155159408aa0bbcc09ab787d777cbecf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "70c7148bb66a6d8b5718a051d27fe8ded8bfbd2ff05429899f1912d3fb83963d"

  strings:
    $s1  = "function EaDeBYrJur(KprwKezE,OYTWBdlBeQEx) {KprwKezE.Run(OYTWBdlBeQEx, 0x1, 0x0);}" fullword ascii
    $s2  = "function HEZYrntTTZ() {return/*NeIEfiuwLyNLyfDShIWEMMARnuFePvkNrzIPnwpRSlehMpvHOBHrgJtraGKTgXDxVzkFUpwrdINFNBmmXbTudALXVTkejjamq" ascii
    $s3  = "function zbXmwAEp(mXlHh) {var yJNkXQmZ=gTPUOHhKTIliq[13];for(var TGoWX=0;TGoWX<mXlHh;TGoWX++){ZJxoQ+=yJNkXQmZ.charAt(Math.floor(" ascii
    $s4  = "function zbXmwAEp(mXlHh) {var yJNkXQmZ=gTPUOHhKTIliq[13];for(var TGoWX=0;TGoWX<mXlHh;TGoWX++){ZJxoQ+=yJNkXQmZ.charAt(Math.floor(" ascii
    $s5  = "nOvn.length;DyhZEuta++) {UGPFAxh+=LtNWG[sWnOvn[DyhZEuta]];}return UGPFAxh.substring(3,UGPFAxh.length);}" fullword ascii
    $s6  = "Math.random()*yJNkXQmZ.length));}return ZJxoQ;}" fullword ascii
    $s7  = "function nuAP(gYAmBqx,EUxcNAH) {gYAmBqx.saveToFile(EUxcNAH, 2);}" fullword ascii
    $s8  = "function voHRtPI() {var rjKO=100000;var zirdkQ = 100;return ohZoawF()*(rjKO-zirdkQ)+zirdkQ;}" fullword ascii
    $s9  = "function ISlKR(jnhiAAog,cSwIU,XBIDWorhbn){mUwz(jnhiAAog);rAdQPXKb(jnhiAAog);HzNoSgE(jnhiAAog,cSwIU);JkmvtyOpa(jnhiAAog);nuAP(jnh" ascii
    $s10 = "function rAdQPXKb(iqQevkElw) {iqQevkElw.type=1;}" fullword ascii
    $s11 = "function LYrBT(XhIzifqG,sWnOvn,eesUdhPNZ){LtNWG=XhIzifqG.split(eesUdhPNZ);UGPFAxh = gTPUOHhKTIliq[12];for(DyhZEuta=0;DyhZEuta<sW" ascii
    $s12 = "function ohZoawF(){return Math.random();}" fullword ascii
    $s13 = "function PkWSw(zOmrRO){return new ActiveXObject(zOmrRO);}" fullword ascii
    $s14 = "function ISlKR(jnhiAAog,cSwIU,XBIDWorhbn){mUwz(jnhiAAog);rAdQPXKb(jnhiAAog);HzNoSgE(jnhiAAog,cSwIU);JkmvtyOpa(jnhiAAog);nuAP(jnh" ascii
    $s15 = "function qgnl(CIFHcB,FOLYrnL){wjCi = gTPUOHhKTIliq[10].split(gTPUOHhKTIliq[11]);FOLYrnL.open(wjCi[0]+wjCi[2]+wjCi[3], CIFHcB, fa" ascii
    $s16 = "function qgnl(CIFHcB,FOLYrnL){wjCi = gTPUOHhKTIliq[10].split(gTPUOHhKTIliq[11]);FOLYrnL.open(wjCi[0]+wjCi[2]+wjCi[3], CIFHcB, fa" ascii
    $s17 = "function HEZYrntTTZ() {return/*NeIEfiuwLyNLyfDShIWEMMARnuFePvkNrzIPnwpRSlehMpvHOBHrgJtraGKTgXDxVzkFUpwrdINFNBmmXbTudALXVTkejjamq" ascii
    $s18 = "function waIhnXeyVCkxW() {HEZYrntTTZ().Sleep(2453350-248);}" fullword ascii
    $s19 = "function LYrBT(XhIzifqG,sWnOvn,eesUdhPNZ){LtNWG=XhIzifqG.split(eesUdhPNZ);UGPFAxh = gTPUOHhKTIliq[12];for(DyhZEuta=0;DyhZEuta<sW" ascii
    $s20 = "function vgWeplM(UUWft) {UUWft.close();}" fullword ascii

  condition:
    uint16(0) == 0x1b27 and
    8 of them
}