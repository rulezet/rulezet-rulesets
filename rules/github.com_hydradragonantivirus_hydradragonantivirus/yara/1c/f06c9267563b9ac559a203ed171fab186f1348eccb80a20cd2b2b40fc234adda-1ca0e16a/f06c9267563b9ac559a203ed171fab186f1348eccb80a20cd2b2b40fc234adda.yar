rule f06c9267563b9ac559a203ed171fab186f1348eccb80a20cd2b2b40fc234adda {
  meta:
    description = "datamaliciousorder - file f06c9267563b9ac559a203ed171fab186f1348eccb80a20cd2b2b40fc234adda.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f06c9267563b9ac559a203ed171fab186f1348eccb80a20cd2b2b40fc234adda"

  strings:
    $x1  = "plannuthate=[];plannuthate['passimportedcoast']='i';plannuthate['motionlessvaluablewriting']='c';plannuthate['parkenginesociety'" ascii
    $s2  = "ay:\"block\"},nt={letterSpacing:\"0\",fontWeight:\"400\"};function rt(e,t,n){var r=Y.exec(t);return r?Math.max(0,r[2]-(n||0))+(r" ascii
    $s3  = ",global:!0,processData:!0,async:!0,contentType:\"application/x-www-form-urlencoded; charset=UTF-8\",accepts:{\"*\":zt,text:\"tex" ascii
    $s4  = ",T,v)||h))return T.abort();if(u=\"abort\",b.add(v.complete),T.done(v.success),T.fail(v.error),c=Vt(_t,v,t,T)){if(T.readyState=1," ascii
    $s5  = "interType:!0,screenX:!0,screenY:!0,targetTouches:!0,toElement:!0,touches:!0,which:!0},ce.event.addProp),ce.each({focus:\"focusin" ascii
    $s6  = ".get(this,i)-1)?_.set(this,i,e):(this.removeEventListener(i,o),_.remove(this,i))},_default:function(e){return _.get(e.target,r)}" ascii
    $s7  = "ts:function(e){return null!=e.contentDocument&&r(e.contentDocument)?e.contentDocument:(fe(e,\"template\")&&(e=e.content||e),ce.m" ascii
    $s8  = "){return ce.css(e,t,\"\")},u=s(),l=n&&n[3]||(ce.cssNumber[t]?\"\":\"px\"),c=e.nodeType&&(ce.cssNumber[t]||\"px\"!==l&&+u)&&Y.exe" ascii
    $s9  = "e\",[T,v]),--ce.active||ce.event.trigger(\"ajaxStop\")))}return T},getJSON:function(e,t,n){return ce.get(e,t,n,\"json\")},getScr" ascii
    $s10 = "unction(e,t){return ce.get(e,void 0,t,\"script\")}}),ce.each([\"get\",\"post\"],function(e,i){ce[i]=function(e,t,n,r){return v(t" ascii
    $s11 = ",blur:\"focusout\"},function(r,i){function o(e){if(C.documentMode){var t=_.get(this,\"handle\"),n=ce.event.fix(e);n.type=\"focus" ascii
    $s12 = "&&ce._evalUrl(u.src,{nonce:u.nonce||u.getAttribute(\"nonce\")},l):m(u.textContent.replace(Me,\"\"),u,l))}return n}function Be(e," ascii
    $s13 = "=e.type?\"focus\":\"blur\",n.isSimulated=!0,t(e),n.target===n.currentTarget&&t(n)}else ce.event.simulate(i,e.target,ce.event.fix" ascii
    $s14 = "in\",html:\"text/html\",xml:\"application/xml, text/xml\",json:\"application/json, text/javascript\"},contents:{xml:/\\bxml\\b/," ascii
    $s15 = "ff:function(e,t,n){var r,i;if(e&&e.preventDefault&&e.handleObj)return r=e.handleObj,ce(e.delegateTarget).off(r.namespace?r.origT" ascii
    $s16 = "T,C)){if(11!==p&&(u=L.exec(t)))if(i=u[1]){if(9===p){if(!(a=e.getElementById(i)))return n;if(a.id===i)return k.call(n,a),n}else i" ascii
    $s17 = "n){return ce.ajax({url:e,type:\"GET\",dataType:\"script\",cache:!0,async:!1,global:!1,converters:{\"text script\":function(){}}," ascii
    $s18 = "t){var n=this.createTween(e,t);return te(n.elem,e,Y.exec(t),n),n}]},tweener:function(e,t){v(e)?(t=e,e=[\"*\"]):e=e.match(D);for(" ascii
    $s19 = "?i:l[t];\"string\"===(o=typeof n)&&(i=Y.exec(n))&&i[1]&&(n=te(e,t,i),o=\"number\"),null!=n&&n==n&&(\"number\"!==o||u||(n+=i&&i[3" ascii
    $s20 = "gth-1]&&3<=e.length?[null,e,null]:S.exec(e))||!r[1]&&t)return!t||t.jquery?(t||n).find(e):this.constructor(t).find(e);if(r[1]){if" ascii

  condition:
    uint16(0) == 0x2a2f and
    1 of ($x*) and 4 of them
}