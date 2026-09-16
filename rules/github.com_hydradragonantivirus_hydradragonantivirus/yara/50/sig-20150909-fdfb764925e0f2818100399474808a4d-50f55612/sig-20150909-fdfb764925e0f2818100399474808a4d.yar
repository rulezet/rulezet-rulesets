rule sig_20150909_fdfb764925e0f2818100399474808a4d {
  meta:
    description = "datamaliciousorder - file 20150909_fdfb764925e0f2818100399474808a4d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "82ebfdc6cdc1b08a7009bd0ed8a4ff12e0e3bbb59dc4c605d64cd7e94277c746"

  strings:
    $x1  = "var HelpPlacardController=Class.create({initialize:function(b){this.domNode=b;this.width=822;this.height=603;var a=[{key:\"&nbsp" ascii
    $s2  = "\",text:kHelpPlacardNavigationTitle,header:true},{key:\"return/enter &nbsp; space &nbsp; &#8594 &nbsp; &#8595 &nbsp; shift - &#8" ascii
    $s3  = "4 &nbsp; page down\",text:kHelpPlacardAdvanceToNextBuild},{key:\"[ &nbsp; shift - page up &nbsp; shift - &#8592\",text:kHelpPlac" ascii
    $s4  = "GoBackToPreviousBuild},{key:\"] &nbsp; shift - page down &nbsp; shift - &#8595 &nbsp; + &nbsp; =\",text:kHelpPlacardAdvanceToNex" ascii
    $s5  = "lide},{key:\"&#8592 &nbsp; &#8593 &nbsp; - &nbsp; shift - &#8593\",text:kHelpPlacardGoBackToPreviousSlide},{key:\"home\",text:kH" ascii
    $s6  = "cSlide},{key:\"&nbsp;\",text:kHelpPlacardOtherTitle,header:true},{key:\"? &nbsp; /\",text:kHelpPlacardShowOrHideKeyboardShortcut" ascii
    $s7  = "startDragging.bindAsEventListener(this))},startDragging:function(a){this.startX=Event.pointerX(a);this.startY=Event.pointerY(a);" ascii
    $s8  = "lacardGoToFirstSlide},{key:\"end\",text:kHelpPlacardGoToLastSlide},{key:\"slide number + return/enter\",text:kHelpPlacardGoToSpe" ascii
    $s9  = "Event:function(a){a=a||window.event;var b=a.target||a.srcElement;if(this.isShowing){if(browserPrefix===\"ms\"){a.cancelBubble=tr" ascii
    $s10 = "bindAsEventListener(this);this.dragStop=this.stopDragging.bindAsEventListener(this);Event.observe(this.domNode,\"mousedown\",thi" ascii
    $s11 = "this.left=parseInt(this.domNode.style.left);this.top=parseInt(this.domNode.style.top);Event.observe(document,\"mousemove\",this." ascii
    $s12 = "var HelpPlacardController=Class.create({initialize:function(b){this.domNode=b;this.width=822;this.height=603;var a=[{key:\"&nbsp" ascii
    $s13 = "key:\"s\",text:kHelpPlacardShowOrHideTheCurrentSlideNumber},{key:\"esc &nbsp; q\",text:kHelpPlacardQuitPresentationMode}];this.h" ascii
    $s14 = "}else{a.stopPropagation()}}this.hide()},setPosition:function(b,a){this.domNode.style.left=b+\"px\";this.domNode.style.top=a+\"px" ascii
    $s15 = "Event.stop(a)}});var HelpPlacardTitleBar=Class.create({initialize:function(){this.domNode=document.createElement(\"div\");this.d" ascii
    $s16 = "Attribute(\"class\",\"helpPlacardRightItem\");b.innerHTML=e.key;d=document.createElement(\"div\");d.setAttribute(\"class\",\"hel" ascii
    $s17 = "header){g.setAttribute(\"class\",\"helpPlacardHeader\");b=document.createElement(\"div\");b.setAttribute(\"class\",\"helpPlacard" ascii
    $s18 = "elpPlacardContentPanel=Class.create({initialize:function(a){this.domNode=document.createElement(\"div\");this.domNode.setAttribu" ascii
    $s19 = "show:function(){this.isShowing=true;this.domNode.style.display=\"block\";this.domNode.style.opacity=1},hide:function(){this.isSh" ascii
    $s20 = "ing=false;this.domNode.style.display=\"none\";this.domNode.style.opacity=0},registerDragEvents:function(){this.drag=this.draggin" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}